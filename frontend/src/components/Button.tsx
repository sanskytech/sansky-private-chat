'use client';

import React from 'react';

interface ButtonProps {
  label: string | React.ReactNode;
  onClick?: () => void;
  className?: string;
  type?: "button" | "submit" | "reset";
  disabled?:boolean;
  spinner?:boolean;

}

const Button: React.FC<ButtonProps> = ({ label, onClick, className , type="button", disabled, spinner=false}) => {
  return (
    <button
    type={type}
    onClick={onClick}
    disabled={disabled}
    className={`relative bg-primary text-white px-4 py-2 rounded disabled:opacity-50 ${className}`}
  >
    {spinner ? <span className="loader inline-block mr-2 w-4 h-4 border-2 border-t-white border-white/20 rounded-full animate-spin"></span> : null}
    {label}
  </button>
  );
};

export default Button;