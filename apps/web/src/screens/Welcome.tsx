import { useState } from 'react';
import { Onboarding } from './Onboarding';
import { SignIn } from './SignIn';

/** Entry point when this device holds no vault: create a new identity or sign in. */
export function Welcome() {
  const [tab, setTab] = useState<'create' | 'signin'>('create');
  if (tab === 'signin') return <SignIn mode="signin" onCreateInstead={() => setTab('create')} />;
  return <Onboarding onSignInInstead={() => setTab('signin')} />;
}
