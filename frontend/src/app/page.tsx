export default function Home() {
  return (
    <div className="relative grid grid-rows-[20px_1fr_20px] items-center justify-items-center min-h-screen p-8 pb-20 gap-16 sm:p-20 font-[family-name:var(--font-geist-sans)]">
      {/* Logo positioned at top-left */}
      <img 
        src="/San-Sec-logo-min.png" 
        alt="Logo" 
        className="absolute top-0 left-0 p-4 w-32 h-auto"
      />

      <main className="flex flex-col gap-8 row-start-2 items-center sm:items-start">
        here should come the content
      </main>
    </div>
  );
}

