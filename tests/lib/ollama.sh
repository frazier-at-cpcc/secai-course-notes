# Shared helper for tests that need a real local language model.
# Source it, then call:  ollama_up <container-name> <port> <model> [model...]
# It starts a CPU-only Ollama image (alpine/ollama, about 120 MB) bound to
# 127.0.0.1:<port> and pulls the models into the shared "ollama-models"
# volume, which caches them between runs. Call
# ollama_down <container-name> from your EXIT trap. chat() sends temperature 0
# and a fixed seed, so a rerun on the same image and model gives the same answer.
#
# Needs: docker, curl, jq

OLLAMA_IMAGE="${OLLAMA_IMAGE:-mirror.gcr.io/alpine/ollama:0.40.6}"

ollama_up() {
  local name="$1" port="$2"; shift 2
  local args=(-d --name "$name" --network host
    -e "OLLAMA_HOST=127.0.0.1:${port}"
    -v ollama-models:/root/.ollama)
  # Behind an HTTPS-inspecting proxy (the authoring sandbox), pass the proxy
  # and its CA through so the container can reach the model registry.
  if [ -n "${HTTPS_PROXY:-}" ]; then
    args+=(-e "HTTPS_PROXY=${HTTPS_PROXY}" -e "NO_PROXY=localhost,127.0.0.1")
  fi
  if [ -f /root/.ccr/ca-bundle.crt ]; then
    args+=(-v /root/.ccr/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro)
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run "${args[@]}" "$OLLAMA_IMAGE" >/dev/null
  OLLAMA_URL="http://127.0.0.1:${port}"
  export OLLAMA_URL
  for _ in $(seq 1 60); do
    curl -sf "$OLLAMA_URL/api/version" >/dev/null && break
    sleep 1
  done
  local m
  for m in "$@"; do
    docker exec "$name" ollama pull "$m" >/dev/null 2>&1 \
      || { echo "could not pull $m" >&2; return 1; }
  done
}

ollama_down() {
  docker rm -f "$1" >/dev/null 2>&1 || true
}

# chat <model> <system-prompt> <user-prompt>  -> prints the reply text
chat() {
  jq -n --arg m "$1" --arg s "$2" --arg u "$3" '{
      model: $m, stream: false,
      options: {temperature: 0, seed: 42},
      messages: ([if $s == "" then empty else {role: "system", content: $s} end]
                 + [{role: "user", content: $u}])
    }' \
  | curl -sf "$OLLAMA_URL/api/chat" -d @- | jq -r .message.content
}
