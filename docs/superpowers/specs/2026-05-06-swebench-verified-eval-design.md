# SWE-bench-Verified 70-case 评测 — 设计

日期：2026-05-06
范围：在 SWE-bench-Verified 数据集上随机抽 70 个 case，跑 minicode（model = glm-5.1），用 sb-cli 云端打分，得到 resolved 率。

## 1. 目标与非目标

**目标**
- 拿到 minicode 在 SWE-bench-Verified 70 个随机样本上的 resolved 率（一个数）。
- 整个流程可复现：固定随机种子、固定 prompt、固定单 case 资源上限。
- 跑崩了能续跑：已生成 patch 的 case 不重跑。

**非目标**
- 不跑全 500。
- 不在本地装 Docker、不本地跑 grading（用 sb-cli 云端打分）。
- 不调 prompt 工程优化分数；这是基线测量，不是冲榜。

## 2. 数据集与抽样

- 数据源：HuggingFace `princeton-nlp/SWE-bench_Verified`（test split，500 条）。
- 抽样：`random.Random(42).sample(dataset, 70)`。
- 抽完落盘到 `bench/sample_70.txt`（每行一个 `instance_id`），人工和后续运行都按这份固定列表，不再重抽。

## 3. minicode 改动

仅改 `main.py`，加非交互入口。

新增标志：
- `--prompt <text>` 或 `--prompt-file <path>`：从命令行/文件读 prompt，作为一次 user message 喂给 `agent_loop`，`agent_loop` 返回后立刻退出。
- `--max-turns <N>`：在 `agent_loop` 里硬截上限。超限就退出。

行为：
- 仍走 `MEMORY.load_all()` / `CRON.start()` / `MCP.start()` / `HOOKS.run("SessionStart")`，结束时走 `SessionEnd` / `CRON.stop()` / `MCP.stop()`，与 REPL 路径一致。
- `--mode yolo` 仍然有效，给 batch 用。
- 退出码：正常 0；超 turn/异常 非 0。

**Usage 上报**：当前 `agent_loop` 没有累计 token。在 `--prompt` 路径里，每轮 `stream.get_final_message()` 拿到 `response.usage`，累加 `input_tokens` / `output_tokens` / `cache_creation_input_tokens` / `cache_read_input_tokens`，退出时写到 `--usage-out <path>` 指定的 JSON 文件：

```
{"turns": 12, "input_tokens": 45230, "output_tokens": 3120,
 "cache_creation_input_tokens": 8200, "cache_read_input_tokens": 38900,
 "wall_clock_seconds": 187.4, "stop_reason": "end_turn"}
```

只在 `--prompt` 路径开启，REPL/TUI 完全不动。

不动 TUI；不动 REPL。

## 4. 评测 harness 布局

```
bench/
  swebench_run.py            # 主驱动脚本
  sample_70.txt              # 70 个 instance_id（固定）
  repo_cache/<owner>__<repo>/   # 每个 repo 克隆一次，缓存
  workspaces/<instance_id>/  # 每个 case 独立 workspace（基于缓存复制 + checkout）
  runs/<run_id>/
    predictions.jsonl        # 每行 {instance_id, model_name_or_path, model_patch}
    usage/<instance_id>.json # 单 case token 计数（minicode 写）
    logs/<instance_id>.log   # minicode stdout/stderr
    status.json              # {instance_id: "done"|"failed"|"timeout"}
    token_report.json        # 70 个 case 的 token 汇总
```

## 5. 单 case 流程

```
for instance in sample_70:
    if status[instance.id] == "done": continue           # 续跑
    repo_path = prepare_workspace(instance)              # clone+checkout, 干净
    write prompt.txt at repo_path
    run subprocess:
        minicode --prompt-file prompt.txt
                 --mode yolo
                 --max-turns 60
                 --usage-out runs/<run_id>/usage/<instance_id>.json
                 <repo_path>
        timeout=1800s
    patch = git -C <repo_path> diff                      # 排除 .minicode/ .memory/
    append {instance_id, model_name_or_path: "minicode-glm-5.1", model_patch: patch}
        to predictions.jsonl
    status[instance.id] = "done"|"timeout"|"failed"
```

`prepare_workspace`：
- 如果 `repo_cache/<repo>` 不存在，`git clone https://github.com/<repo>.git`（一次性，浅克隆不行因为要 checkout 任意 commit，所以全克隆）。
- 用 `git worktree add` 或 `cp -R`+`git checkout` 在 `workspaces/<instance_id>/` 准备一份在 `base_commit` 上的工作树。优先 `git worktree add`（更省盘）。
- 在 workspace 里写 `.gitignore` 追加 `.minicode/` `.memory/`，避免 minicode 自身落的状态进入 diff。

`git diff` 提取（含未追踪文件、排除 minicode 自身落的状态）：

```
git -C <repo_path> add -A -- \
    ':!.minicode' ':!.memory' ':!prompt.txt' ':!.gitignore'
git -C <repo_path> diff --cached HEAD
git -C <repo_path> reset                 # 不留 staging 痕迹
```

这样能把新增源文件包进 patch，又不让 minicode 自己写的 `.minicode/` `.memory/` 污染 diff。

## 6. Prompt 模板

```
You are fixing a real GitHub issue in this repository.

<issue>
{problem_statement}
</issue>

Constraints:
- Modify only source files needed to fix the issue.
- Do NOT modify test files.
- Do NOT add new dependencies.
- When done, stop. The git diff of your changes will be graded.

Repository root: {repo_path}
Base commit: {base_commit}
```

不带 hints / chain-of-thought 引导。基线就用这个。

## 7. 并发

- 默认 `--workers 4`。
- 用 `concurrent.futures.ProcessPoolExecutor` 起 4 个 worker，每个 worker 跑一个 case 的完整子流程。
- `predictions.jsonl` 写入加文件锁（`fcntl.flock`），防并发写错位。
- `repo_cache` 的克隆用 per-repo 锁，第一个 worker 克隆，其它等。

## 8. 单 case 资源上限

- `--max-turns 60`
- wall-clock `timeout=1800s`（30 分钟）
- 命中任一上限：当作 failed/timeout，patch 仍按 git diff 抓（可能是空 diff），不阻塞后续 case。

## 9. 打分（云端）

跑完拿到 `bench/runs/<run_id>/predictions.jsonl` 后：

```
pip install sb-cli
export SWEBENCH_API_KEY=...
sb-cli submit swe-bench-verified test \
    --predictions_path bench/runs/<run_id>/predictions.jsonl \
    --run_id minicode-glm-5.1-<run_id>
sb-cli get-report swe-bench-verified <run_id>
```

报告里 `resolved` / `total` 即为最终性能数。注意 sb-cli 是按全 500 算总数还是按提交的子集算 — 看到报告再确认；我们关心的是"我们提交的 70 条里 resolved 多少"。

## 9.5 Token 汇总

跑完后 `swebench_run.py --report` 读取 `runs/<run_id>/usage/*.json`，输出 `token_report.json`：

```
{
  "model": "glm-5.1",
  "n_cases": 70,
  "n_completed": 68,
  "totals": {
    "input_tokens": 3120000,
    "output_tokens": 210000,
    "cache_creation_input_tokens": 480000,
    "cache_read_input_tokens": 2700000,
    "turns": 712,
    "wall_s": 9824.5
  },
  "per_case": [
    {"instance_id": "...", "input_tokens": 45230, "output_tokens": 3120,
     "cache_creation_input_tokens": 8200, "cache_read_input_tokens": 38900,
     "turns": 12, "wall_s": 187.4},
    ...
  ]
}
```

终端打印：`total in/out/cache_w/cache_r tokens, mean per case, completed N/70`。不做金额折算。

终端打印：`total ¥X.YZ, mean ¥A.BC/case, completed N/70`。

## 10. 输出

- `bench/runs/<run_id>/predictions.jsonl` — 提交给 sb-cli 用。
- `bench/runs/<run_id>/logs/*.log` — 每个 case 的 minicode 完整输出，便于事后排查。
- `bench/runs/<run_id>/status.json` — done/timeout/failed 汇总。
- 终端输出：每 case 跑完打印 `[ok] <id> patch=<bytes>` 或 `[timeout] <id>`；全部跑完打印汇总。

## 11. 风险与注意

- **glm-5.1 走的是智谱代理**（`ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic`），稳定性 / 限流可能与官方 Anthropic 不同；并发 4 时可能 429。脚本要带退避重试。
- **某些 SWE-bench repo 很大**（如 sympy、django）：`git clone` 慢，第一次准备阶段会有几分钟开销。
- **空 diff 也算一条提交**：sb-cli 应当判 unresolved，不会报错；保留即可。
- **minicode 自身可能写 `.memory/`、`.minicode/`、`docs/code-review-report*` 等**：靠 `.gitignore` + diff pathspec 排除。
- **续跑语义**：`status.json` 是 source of truth；重新跑只补 `done` 之外的。

## 12. 不在范围内

- 不调超参 / 多 sample / self-consistency。
- 不写 CI / 不做长期回归基础设施 — 这是一次性测量。
- 不在 minicode 主路径（REPL/TUI）暴露 usage 显示；只在 `--prompt` 批跑时记录到文件。
