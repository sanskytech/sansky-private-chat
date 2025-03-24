import AnimatedLink from "@/components/AnimatedLink";

import Image from 'next/image';
import Link from "next/link";


export default function Home() {
  return (
    <div>
        <Link href="/">
          <Image 
            src="/San-Sec-logo-min.png" 
            alt="Logo" 
            width={128}
            height={128}
            className="absolute top-0 left-0 p-4 z-10"
          />
        </Link>
      <main className="flex flex-col gap-8 mt-40 justify-center items-center">
         <h1 className="text-center">Welcome to Sansyktech</h1>	
         <p className="text-md md:text-lg text-center">This is a private chat application</p>
         <AnimatedLink href="/create">Start from here</AnimatedLink>

      </main>
    </div>
  );
}

