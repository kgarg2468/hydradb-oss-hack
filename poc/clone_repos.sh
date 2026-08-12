#!/usr/bin/env bash
# Blobless clones of candidate repos. Blobs are lazily fetched later in one
# batched `git cat-file --batch` pass by extract_history.py.
set -u
cd "$(dirname "$0")/repos" || exit 1

REPOS=(
  "eslint https://github.com/eslint/eslint.git"
  "express https://github.com/expressjs/express.git"
  "axios https://github.com/axios/axios.git"
  "superset https://github.com/apache/superset.git"
  "jitsi-meet https://github.com/jitsi/jitsi-meet.git"
  "react https://github.com/facebook/react.git"
  "webpack https://github.com/webpack/webpack.git"
  "storybook https://github.com/storybookjs/storybook.git"
  "grafana https://github.com/grafana/grafana.git"
  "babel https://github.com/babel/babel.git"
)

for entry in "${REPOS[@]}"; do
  name="${entry%% *}"
  url="${entry#* }"
  if [ -d "$name/.git" ]; then
    echo "SKIP $name (exists)"
    continue
  fi
  echo "CLONE $name"
  git clone --filter=blob:none --no-checkout --single-branch "$url" "$name" \
    >"clone-$name.log" 2>&1 && echo "OK $name" || echo "FAIL $name"
done
echo "ALL DONE"
