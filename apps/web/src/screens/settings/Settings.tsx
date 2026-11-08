import { DataSection } from './DataSection';
import { DevicesSection } from './DevicesSection';
import { KeysSection } from './KeysSection';
import { PanicResetSection } from './PanicResetSection';
import { PrivacySection } from './PrivacySection';

export type SettingsSection = 'privacy' | 'devices' | 'keys' | 'data' | 'panic';

export const SECTIONS: { id: SettingsSection; label: string; danger?: boolean }[] = [
  { id: 'privacy', label: 'Privacy' },
  { id: 'devices', label: 'Devices & sessions' },
  { id: 'keys', label: 'Keys & recovery' },
  { id: 'data', label: 'Data' },
  { id: 'panic', label: 'Panic Reset', danger: true },
];

/** The open settings section. Section navigation lives in the app rail. */
export function SettingsPage({ section, onBack }: { section: SettingsSection; onBack: () => void }) {
  return (
    <div className="page-scroll">
      <div className="page">
        <button type="button" className="link-btn page-back" onClick={onBack}>
          Settings
        </button>
        {section === 'privacy' && <PrivacySection />}
        {section === 'devices' && <DevicesSection />}
        {section === 'keys' && <KeysSection />}
        {section === 'data' && <DataSection />}
        {section === 'panic' && <PanicResetSection />}
      </div>
    </div>
  );
}
