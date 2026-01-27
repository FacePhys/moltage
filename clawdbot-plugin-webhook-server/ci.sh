set -e
git pull
npm run build
clawdbot plugins install -l .
clawdbot gateway restart

