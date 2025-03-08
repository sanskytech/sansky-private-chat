'use client';

import Link from 'next/link';
import { FC, ReactNode } from 'react';

interface AnimatedLinkProps {
  href: string;
  children: ReactNode;
  className?: string;
}

const AnimatedLink: FC<AnimatedLinkProps> = ({ href, children, className = '' }) => {
  return (
    <Link
      href={href}
      className={`group bg-primary hover:bg-primary/80   text-white font-bold py-2 px-4 rounded transition-all inline-flex items-center gap-1 ${className}`}
    >
      {children}
      <span 
        className="text-sm transition-transform group-hover:translate-x-2 "
      >
        →
      </span>
    </Link>
  );
};

export default AnimatedLink;
