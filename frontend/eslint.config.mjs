import nextVitals from "eslint-config-next/core-web-vitals";

const config = [
  ...nextVitals,
  {
    ignores: [".next/**", "coverage/**", "playwright-report/**", "test-results/**"],
    rules: {
      "react-hooks/set-state-in-effect": "off",
    },
  },
];

export default config;
