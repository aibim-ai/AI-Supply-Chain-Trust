export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui"],
        mono: ["JetBrains Mono", "ui-monospace"],
      },
      colors: { ink: "#101828", brand: "#635bff" },
      boxShadow: { soft: "0 18px 50px rgba(16,24,40,.08)" },
    },
  },
  plugins: [],
};
