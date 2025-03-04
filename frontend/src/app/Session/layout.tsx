import type { Metadata } from "next";


export const metadata: Metadata = {
  title: "create or join a room",
  description: "This page allows you to create or join a room",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={` antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
