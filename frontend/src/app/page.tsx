export default function Home() {
  return (
    <div
      className="grid grid-rows-[20px_1fr_20px] items-center justify-items-center min-h-screen p-8 pb-20 gap-16 sm:p-20 font-[family-name:var(--font-geist-sans)]"
      style={{
        backgroundImage: "url('/background-create-page.png')", // Path to the image in public folder
        backgroundSize: 'cover', // Make sure it covers the whole screen
        backgroundPosition: 'center', // Position the image in the center
      }}
    >
      <main className="flex flex-col gap-8 row-start-2 items-center sm:items-start">
        here should come the content
      </main>
    </div>
  );
}

