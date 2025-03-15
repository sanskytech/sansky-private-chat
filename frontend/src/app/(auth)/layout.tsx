import Image from 'next/image';
import Link from "next/link";



export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
      <div
        className={`antialiased justify-center items-center flex flex-col h-screen`}
      >
        <Link href="/">
          <Image 
            src="/San-Sec-logo-min.png" 
            alt="Logo" 
            width={128}
            height={128}
            className="absolute top-0 left-0 p-4 z-19 "
          />
        </Link>

        {children}
      </div>
  );
}
