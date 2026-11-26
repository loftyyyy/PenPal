# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some Oxlint rules.

## PenPal design system

Shared design tokens and component styles live in `src/index.css`. Keep new and updated screens on this system instead of introducing page-specific colors, type sizes, control dimensions, or radii.

- Wrap authenticated page content in `.ui-page`; use `.ui-login` for the login screen.
- Use the `--color-*`, `--text-*`, `--spacing-*`, and `--radius-*` CSS variables for custom styling.
- Use `.ui-panel`, `.ui-table-container` with `.ui-table`, and `.ui-badge` with a status variant for shared surfaces, tables, and status indicators.
- Buttons use the shared button rules; set `data-variant` to `primary`, `outline`, `danger`, or `ghost` when a non-default variant is needed. Use `.ui-button` for buttons outside `.ui-page` and for button-styled links.
- Inputs, selects, textareas, headings, and labels inside `.ui-page` use the shared form and typography rules automatically.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the Oxlint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and Oxlint's TypeScript related rules in your project.
