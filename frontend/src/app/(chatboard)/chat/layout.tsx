
import React from "react";


export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <div className={`flex `}>
      {/* left navigation */}
      <div className={`w-1/4 bg-gray-200 h-screen`}>
          <h2>Left Navigation</h2>
      </div>
      {/* body */}
      
      <div className={`w-3/4 bg-gray-100 h-screen`}>
         {children}
      </div>
    </div>
  );
}
