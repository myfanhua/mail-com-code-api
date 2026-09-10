#!/usr/bin/env bash

# mail.com 接码 API 本地进程管理脚本
# 用法：./service.sh {start|stop|restart|status|logs}

set -u

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_FILE="$APP_DIR/server.py"
RUN_DIR="${MAIL_API_RUN_DIR:-$APP_DIR/.run}"
LOG_DIR="${MAIL_API_LOG_DIR:-$APP_DIR/logs}"
PID_FILE="$RUN_DIR/server.pid"
LOG_FILE="${MAIL_API_LOG_FILE:-$LOG_DIR/server.log}"
ENV_FILE="${MAIL_API_ENV_FILE:-$APP_DIR/.env}"

say() {
  printf '%s\n' "$*"
}

die() {
  printf '错误：%s\n' "$*" >&2
  exit 1
}

load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    # .env 应使用 KEY=value 格式；导出变量供 server.py 读取。
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
  fi

  MAIL_API_PORT="${MAIL_API_PORT:-8988}"
  MAIL_API_BIND="${MAIL_API_BIND:-0.0.0.0}"
  MAIL_API_PUBLIC_BASE="${MAIL_API_PUBLIC_BASE:-http://127.0.0.1:${MAIL_API_PORT}}"
  export MAIL_API_BIND MAIL_API_PORT MAIL_API_PUBLIC_BASE
}

find_python() {
  if [[ -n "${MAIL_API_PYTHON:-}" ]]; then
    PYTHON="$MAIL_API_PYTHON"
  elif [[ -x "$APP_DIR/.venv/bin/python" ]]; then
    PYTHON="$APP_DIR/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON="$(command -v python3)"
  else
    die "未找到 Python，请创建 .venv 或设置 MAIL_API_PYTHON"
  fi

  [[ -x "$PYTHON" ]] || die "Python 不可执行：$PYTHON"
}

read_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ "$PID" =~ ^[0-9]+$ ]] || return 1
}

is_running() {
  read_pid || return 1
  kill -0 "$PID" 2>/dev/null || return 1
  # 避免 PID 被系统复用后误操作其他进程。
  ps -p "$PID" -o command= 2>/dev/null | grep -F -- "$SERVER_FILE" >/dev/null
}

clean_stale_pid() {
  if [[ -f "$PID_FILE" ]] && ! is_running; then
    rm -f "$PID_FILE"
  fi
}

health_host() {
  case "${MAIL_API_BIND:-127.0.0.1}" in
    0.0.0.0|::|'[::]') printf '127.0.0.1' ;;
    *) printf '%s' "${MAIL_API_BIND:-127.0.0.1}" ;;
  esac
}

health_check() {
  "$PYTHON" - "$(health_host)" "${MAIL_API_PORT:-8988}" <<'PY' >/dev/null 2>&1
import sys
import urllib.request

host, port = sys.argv[1], sys.argv[2]
with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=1) as response:
    if response.status != 200:
        raise SystemExit(1)
PY
}

start_service() {
  load_env
  find_python
  mkdir -p "$RUN_DIR" "$LOG_DIR" "$(dirname "$LOG_FILE")"
  clean_stale_pid

  if is_running; then
    say "服务已在运行（PID ${PID}）"
    return 0
  fi

  [[ -f "$SERVER_FILE" ]] || die "找不到 $SERVER_FILE"
  say "正在启动服务……"
  (
    cd "$APP_DIR" || exit 1
    nohup "$PYTHON" "$SERVER_FILE" >>"$LOG_FILE" 2>&1 </dev/null &
    printf '%s\n' "$!" >"$PID_FILE"
  )

  local attempt
  for attempt in {1..30}; do
    if ! is_running; then
      rm -f "$PID_FILE"
      printf '启动失败，请查看日志：%s\n' "$LOG_FILE" >&2
      tail -n 20 "$LOG_FILE" >&2 2>/dev/null || true
      return 1
    fi
    if health_check; then
      say "启动成功（PID ${PID}，http://$(health_host):${MAIL_API_PORT:-8988}）"
      say "日志：$LOG_FILE"
      return 0
    fi
    sleep 0.5
  done

  printf '进程已启动，但健康检查超时，请查看：%s\n' "$LOG_FILE" >&2
  return 1
}

stop_service() {
  clean_stale_pid
  if ! is_running; then
    say "服务未运行"
    return 0
  fi

  local old_pid="$PID"
  say "正在停止服务（PID ${old_pid}）……"
  kill "$old_pid"

  local attempt
  for attempt in {1..20}; do
    if ! kill -0 "$old_pid" 2>/dev/null; then
      rm -f "$PID_FILE"
      say "服务已停止"
      return 0
    fi
    sleep 0.5
  done

  say "普通停止超时，正在强制停止……"
  kill -9 "$old_pid" 2>/dev/null || true
  rm -f "$PID_FILE"
  say "服务已停止"
}

status_service() {
  load_env
  find_python
  clean_stale_pid
  if is_running; then
    if health_check; then
      say "服务运行正常（PID ${PID}，http://$(health_host):${MAIL_API_PORT:-8988}）"
      return 0
    fi
    say "服务进程存在（PID ${PID}），但健康检查失败"
    return 1
  fi
  say "服务未运行"
  return 3
}

show_logs() {
  mkdir -p "$LOG_DIR" "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
  tail -n 100 -f "$LOG_FILE"
}

usage() {
  cat <<EOF
用法：$(basename "$0") {start|stop|restart|status|logs}

  start    后台启动服务
  stop     停止服务
  restart  重启服务
  status   查看进程及健康状态
  logs     持续查看标准输出和错误日志

可选环境变量：
  MAIL_API_PYTHON    Python 可执行文件路径
  MAIL_API_ENV_FILE  配置文件路径（默认：$APP_DIR/.env）
  MAIL_API_RUN_DIR   PID 文件目录（默认：$APP_DIR/.run）
  MAIL_API_LOG_DIR   日志目录（默认：$APP_DIR/logs）
  MAIL_API_LOG_FILE  日志文件（默认：$APP_DIR/logs/server.log）
EOF
}

case "${1:-}" in
  start) start_service ;;
  stop) stop_service ;;
  restart)
    stop_service
    start_service
    ;;
  status) status_service ;;
  logs) show_logs ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
