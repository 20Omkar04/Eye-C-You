# Eye-C-You
A mathematical working model for Homomorphic Encryption on Cloud

# 1. Create a new Vite + React project

Open the VS Code terminal (Ctrl+`` ) and run:

bashnpm create vite@latest eye-c-you -- --template react
cd eye-c-you
npm install

# 2. Install Tailwind CSS

bashnpm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
Then open tailwind.config.js and replace its content with:
jsexport default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: { extend: {} },
  plugins: [],
}

Open src/index.css and replace everything with:

css@tailwind base;
@tailwind components;
@tailwind utilities;

# 3. Place the files

Copy the downloaded files into your project like this:

eye-c-you/
└── src/
    ├── logic/
    │   └── paillierEngine.js        ← paste here
    ├── utils/
    │   └── supabaseClient.js        ← paste here
    ├── components/
    │   └── BiometricDashboard.jsx   ← paste here
    ├── App.jsx
    └── main.jsx
    
Create the folders manually or via terminal:

bashmkdir src/logic src/utils src/components

# 4. Wire up App.jsx

Open src/App.jsx and replace everything with:

jsximport BiometricDashboard from "./components/BiometricDashboard";
import "./index.css";

export default function App() {
  return <BiometricDashboard />;
}

# 5. Add Supabase (optional but recommended)

bashnpm install @supabase/supabase-js

Create a .env file in the project root:

VITE_SUPABASE_URL=https://your-project-ref.supabase.co

VITE_SUPABASE_ANON_KEY=your-anon-key-here

# 6. Run it

bashnpm run dev
