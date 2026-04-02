curl -fsSL https://bun.sh/install | bash;

cd frontend;
bun i;
bun run --bun build;
cd ..;

bun i;
bun api-server.ts;

