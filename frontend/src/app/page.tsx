import AnimatedLink from "@/components/AnimatedLink";


export default function Home() {
  return (
    <div>
      <main className="flex flex-col gap-8 mt-40 justify-center items-center">
         <h1 className="text-4xl font-bold">Welcome to Sansyktech</h1>	
         <p className="text-lg">This is a private chat application</p>
         <AnimatedLink href="/create">Start from here</AnimatedLink>
      </main>
    </div>
  );
}

