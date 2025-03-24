'use client';

import React from 'react';
import TextField from '@mui/material/TextField';

interface TextInputFieldProps {
  label: string;
  required?: boolean;
  id?: string;
  value?: string;
  className?: string;
  onChange?: (event: React.ChangeEvent<HTMLInputElement>) => void;
  size?: "small"|"medium"
}

const TextInputField: React.FC<TextInputFieldProps> = ({size="medium", value, label, required = false, id, className, onChange }) => {
  return (
    <TextField
      required={required}
      id={id || 'outlined-required'}
      label={label}
      margin="normal"
      className={` rounded-xl [&>div]:!rounded-xl my-10 bg-white border border-[#0795C6] focus:border-[#0795C6] hover:border-[#0795C6] ${className}`}
      onChange={onChange}
      value={value}
      size={size}
    />
  );
};

export default TextInputField;
