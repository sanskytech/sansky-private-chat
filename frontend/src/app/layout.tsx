import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "../global.css";

import Image from 'next/image';
import Link from "next/link";


const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Private Sansky Chat",
  description: "A private chat application",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <Link href="/">
          <Image 
            src="/San-Sec-logo-min.png" 
            alt="Logo" 
            width={128}
            height={128}
            className="absolute top-0 left-0 p-4 z-10"
          />
        </Link>

        {children}
      </body>
    </html>
  );
}
