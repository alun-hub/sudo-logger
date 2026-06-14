# Task 01: Project Setup — Vite + React + TypeScript + Tailwind + shadcn/ui

## Context
We are migrating the replay-server frontend from a single 347KB vanilla JS
`index.html` to a React + TypeScript SPA built with Vite. The Go server at
`go/cmd/replay-server/main.go` embeds the `static/` directory via
`//go:embed static`. The build output must land in
`go/cmd/replay-server/static/` so Go can continue to embed it unchanged.

This task creates the empty project scaffold. No components are written yet.

## Working directory
`/home/alun/sudo-logger`

## Prerequisites
- Node.js ≥ 20 installed
- npm ≥ 10 installed

## Steps

### 1. Create Vite project

```bash
cd go/cmd/replay-server
npm create vite@latest ui -- --template react-ts
cd ui
npm install
```

### 2. Install dependencies

```bash
# Tailwind v4 + Vite plugin
npm install -D tailwindcss @tailwindcss/vite

# shadcn/ui peer deps
npm install class-variance-authority clsx tailwind-merge lucide-react

# Routing
npm install react-router-dom

# Data fetching
npm install @tanstack/react-query

# Terminal
npm install @xterm/xterm @xterm/addon-fit

# Testing
npm install -D vitest @testing-library/react @testing-library/jest-dom @vitejs/plugin-react jsdom
```

### 3. Write vite.config.ts

Replace the generated `go/cmd/replay-server/ui/vite.config.ts` with:

```ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  build: {
    outDir: '../static',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api':       'http://localhost:8080',
      '/approvals': 'http://localhost:8080',
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
  },
})
```

### 4. Write tsconfig.json

Replace `go/cmd/replay-server/ui/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "bundler",
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": ".",
    "paths": { "@/*": ["./src/*"] },
    "allowImportingTsExtensions": true,
    "moduleDetection": "force",
    "skipLibCheck": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

### 5. Write src/index.css (Tailwind v4)

Replace `go/cmd/replay-server/ui/src/index.css` with:

```css
@import "tailwindcss";
```

### 6. Initialize shadcn/ui

```bash
cd go/cmd/replay-server/ui
npx shadcn@latest init
```

When prompted:
- Style: **Default**
- Base color: **Zinc**
- CSS variables: **Yes**

This creates `components.json` and updates `src/index.css`.

### 7. Add test setup file

Create `go/cmd/replay-server/ui/src/test/setup.ts`:

```ts
import '@testing-library/jest-dom'
```

### 8. Write minimal src/main.tsx

```tsx
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import './index.css'

const queryClient = new QueryClient()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </BrowserRouter>
  </StrictMode>
)
```

### 9. Write minimal src/App.tsx

```tsx
export default function App() {
  return <div className="p-4 text-zinc-900 dark:text-zinc-100">sudo-logger</div>
}
```

### 10. Copy logo assets

```bash
cp go/cmd/replay-server/static/logo.svg        go/cmd/replay-server/ui/public/logo.svg
cp go/cmd/replay-server/static/logo-icon-72.svg go/cmd/replay-server/ui/public/logo-icon-72.svg
```

### 11. Add package.json scripts (verify they exist)

Ensure `go/cmd/replay-server/ui/package.json` has:

```json
{
  "scripts": {
    "dev":   "vite",
    "build": "tsc -b && vite build",
    "test":  "vitest",
    "lint":  "tsc --noEmit"
  }
}
```

## Verification

```bash
cd go/cmd/replay-server/ui

# Dev server starts without errors
npm run dev
# → open http://localhost:5173, should show "sudo-logger"

# Build succeeds and writes to ../static/
npm run build
ls ../static/
# → index.html, assets/

# TypeScript passes
npm run lint

# Tests run (0 tests is OK)
npm run test -- --run
```

## Output for next task
After this task, `go/cmd/replay-server/ui/` is a working Vite project.
Task 02 will add the API layer and TypeScript types.
