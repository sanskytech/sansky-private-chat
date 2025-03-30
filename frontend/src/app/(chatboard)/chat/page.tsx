"use client";

import Sidebar from "@/components/Sidebar";


export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <div className={`flex `}>
      {/* Left Navigation */}
      <Sidebar showCollapsedIcon={false} classNames={'w-full md:w-1/3'} />
      {/* Body */}
      {/* <div className={`hidden md:block md:p-10 flex-1 bg-gray-100 h-screen scroll-smooth `}>{children}</div> */}
    </div>
  );
}
