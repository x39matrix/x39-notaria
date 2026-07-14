import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import NotariaApp from './notaria/NotariaApp';

export default function Root() {
  return (
    <BrowserRouter>
      <NotariaApp />
    </BrowserRouter>
  );
}
