'use client';

import React from 'react';

interface ButtonProps {
  label: string | React.ReactNode;
  onClick?: () => void;
  className?: string;
}

const Button: React.FC<ButtonProps> = ({ label, onClick, className }) => {
  return (
    <button
      className={`text-white h-12 font-bold py-2 px-4 rounded-xl cursor-pointer bg-[#2F98BC] ${className}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
};

export default Button;