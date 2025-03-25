"use client";

import {  useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

const CountdownPage = () => {
  const searchParams = useSearchParams();
  // const code = searchParams.get("code"); 
  const usename = searchParams.get("username");

  const [timeLeft, setTimeLeft] = useState(5 * 60); 

  useEffect(() => {
    if (timeLeft <= 0) return;

    const timer = setInterval(() => {
      setTimeLeft((prev) => prev - 1);
    }, 1000);

    return () => clearInterval(timer);
  }, [timeLeft]);

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}:${secs < 10 ? "0" : ""}${secs}`;
  };

  return (
    <div className="w-11/12 max-w-md mx-auto  flex flex-col items-center justify-center min-h-screen text-gray-900">
      <h1 className="text-4xl font-bold">Welcome {usename || "N/A"}</h1>
      <p className="text-xl md:text-3xl text-center ">We notify the admin, please wait until someone lets you in!</p>
      <p className="text-2xl mt-4">Time Left: {formatTime(timeLeft)}</p>
      <div className="mt-10">
      <span className="relative flex size-20">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75"></span>
      <span className="relative inline-flex size-20 rounded-full bg-color-primary/60"></span>
</span>
      </div>
    </div>
  );
};

export default CountdownPage;