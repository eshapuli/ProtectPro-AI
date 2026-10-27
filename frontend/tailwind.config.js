/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          900: '#0a192f',
          800: '#112240',
          700: '#233554',
        },
        slate: {
          300: '#a8b2d1',
          400: '#8892b0',
          500: '#ccd6f6',
        },
        accent: {
          blue: '#64ffda',
          red: '#ff6b6b',
          orange: '#ffa94d',
        }
      }
    },
  },
  plugins: [],
}
