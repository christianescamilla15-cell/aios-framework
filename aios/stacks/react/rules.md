# React Stack Rules

## Structure
- Components in src/components/ organized by feature
- Services/API in src/services/
- Hooks in src/hooks/
- Constants in src/constants/
- Utils in src/utils/

## Components
- Functional components only (no class components)
- Custom hooks for shared logic
- Error boundaries for critical sections
- Accessible: aria labels, keyboard navigation

## State
- Local state for UI-only (useState)
- Context or Zustand for shared state
- No prop drilling beyond 2 levels

## API
- Centralized API client (src/services/api.js)
- Error handling with fallback UI
- Loading states for async operations
- Never expose API keys in frontend code

## Build
- Vite for bundling
- ESLint for linting
- Vitest for testing
- Build must pass before deploy

## Performance
- Memoize expensive computations
- Lazy load heavy components
- Optimize images and assets
- Bundle size < 500KB gzipped
