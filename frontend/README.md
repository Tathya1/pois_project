# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.

## PA#3 — IND-CPA Demo

The PA#3 panel lets you play the IND-CPA game and test the broken nonce-reuse variant. It talks to these backend routes:

- `POST /cpa/challenge` — returns the challenge ciphertext for $m_b$
- `POST /cpa/guess` — submit your guess and reveal $b$
- `POST /cpa/oracle` — encryption oracle for chosen-message queries
- `POST /cpa/simulate` — dummy adversary (50 oracle queries)
- `POST /cpa/rounds` — auto-run 20 rounds to see the advantage trend
