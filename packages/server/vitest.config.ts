import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    env: {
      DATABASE_URL: 'postgresql://clavum:clavum_dev@localhost:5434/clavum',
    },
  },
});
