import { useSnapshot } from '../lib/context';
import type { SettingsSection } from './settings/Settings';

export function SecurityInfo({ onOpenSettings }: { onOpenSettings: (s: SettingsSection) => void }) {
  const snap = useSnapshot();
  const verified = snap.conversations.filter((c) => c.verification === 'verified').length;
  const changed = snap.conversations.filter((c) => c.verification === 'key-changed').length;
  const unverified = snap.conversations.length - verified - changed;

  return (
    <div className="page-scroll">
      <div className="page">
        <h1>How VEIL protects you</h1>
        <p className="page-lede">
          What the server can and cannot see, how your messages are encrypted, and the limits you should know about.
        </p>

        <section className="card" aria-labelledby="state-h">
          <h3 id="state-h">This device</h3>
          <div className="table-wrap">
            <table className="table">
              <tbody>
                <tr>
                  <th scope="row">Identity</th>
                  <td className="username">{snap.username}</td>
                </tr>
                <tr>
                  <th scope="row">Device role</th>
                  <td>{snap.isPrimary ? 'Primary: holds your identity key' : 'Linked: cannot add or remove devices'}</td>
                </tr>
                <tr>
                  <th scope="row">Recovery key</th>
                  <td>
                    {snap.recoveryEnabled ? 'Set up' : 'Not set up. A lost device or forgotten password cannot be recovered.'}{' '}
                    <button type="button" className="link-btn" onClick={() => onOpenSettings('keys')}>
                      Manage
                    </button>
                  </td>
                </tr>
                <tr>
                  <th scope="row">Contacts</th>
                  <td>
                    {verified} verified · {unverified} not verified
                    {changed > 0 && <span className="badge badge-warn"> {changed} with changed key</span>}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section className="card" aria-labelledby="server-h">
          <h3 id="server-h">What the server can and cannot access</h3>
          <div className="split-list">
            <div>
              <h4>Cannot</h4>
              <ul className="check-list no small">
                <li>Read your messages, attachments or display name</li>
                <li>Learn your password or any private key</li>
                <li>See who sent a stored message</li>
                <li>Add a device to your account</li>
                <li>Restore your data after a password reset</li>
              </ul>
            </div>
            <div>
              <h4>Can</h4>
              <ul className="check-list small">
                <li>See your username and public keys</li>
                <li>See how many encrypted messages wait for each device, and their sizes</li>
                <li>See connection details (IP address, timing) while you are connected</li>
                <li>Refuse service or delay messages</li>
              </ul>
            </div>
          </div>
        </section>

        <section className="card" aria-labelledby="crypto-h">
          <h3 id="crypto-h">The encryption, in plain terms</h3>
          <ul className="small">
            <li>
              <strong>Your keys are created on your device</strong> and never sent to the server. An identity key represents you;
              each device has its own keys, listed in a device list signed by your identity key.
            </li>
            <li>
              <strong>Starting a conversation</strong> uses X3DH, the key agreement from the Signal protocol, so two devices agree on
              a secret without the server learning it.
            </li>
            <li>
              <strong>Every message</strong> is encrypted with the Double Ratchet: each message uses a fresh key, and old keys are
              deleted. Someone who steals your device later cannot decrypt past messages it no longer stores (forward secrecy), and
              the conversation heals after a temporary key compromise.
            </li>
            <li>
              <strong>Sealed sender:</strong> the sender's identity is inside the encryption, so stored messages say only which device
              they are for.
            </li>
            <li>
              Messages and files use XChaCha20-Poly1305, which detects any tampering. Your password is stretched with Argon2id
              before anything is derived from it.
            </li>
            <li>VEIL uses only published, reviewed algorithms and protocols. It does not invent its own.</li>
          </ul>
        </section>

        <section className="card" aria-labelledby="verify-h">
          <h3 id="verify-h">Verification states</h3>
          <div className="table-wrap">
            <table className="table">
              <tbody>
                <tr>
                  <th scope="row">
                    <span className="badge">Not verified</span>
                  </th>
                  <td>
                    Encrypted, but you have not confirmed the keys belong to the right person. A malicious server could, in principle,
                    have handed you its own keys the first time.
                  </td>
                </tr>
                <tr>
                  <th scope="row">
                    <span className="badge badge-accent">Verified</span>
                  </th>
                  <td>You compared the 60-digit safety number with your contact and it matched.</td>
                </tr>
                <tr>
                  <th scope="row">
                    <span className="badge badge-warn">Key changed</span>
                  </th>
                  <td>
                    Their identity key is different from before. Sending pauses until you accept it. Compare the safety number again.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section className="card" aria-labelledby="recovery-h">
          <h3 id="recovery-h">Recovery limits</h3>
          <p className="small">
            Your password unlocks this device and signs you in. The recovery key restores your identity key from an encrypted backup.
            Message history lives only on your devices. If you lose your password and your recovery key, or every primary device and
            your recovery key, your identity cannot be restored by anyone. A new password set without the recovery key would never
            unlock old data.
          </p>
        </section>

        <section className="card" aria-labelledby="limits-h">
          <h3 id="limits-h">What VEIL cannot protect against</h3>
          <ul className="check-list danger small">
            <li>
              <strong>VEIL is not anonymous against a powerful network observer.</strong> Someone who watches traffic at both ends
              can correlate when messages are sent and received. Use Tor or a trusted VPN if that matters to you.
            </li>
            <li>
              <strong>A compromised device.</strong> Malware on your or your contact's device can read messages after they are
              decrypted. Encryption protects messages in transit and on the server, not on a hacked phone or computer.
            </li>
            <li>
              <strong>Your contacts.</strong> Anyone you message can keep, copy or screenshot what you send.
            </li>
            <li>
              <strong>Metadata the network creates.</strong> Your IP address, connection times and message sizes are visible to your
              network and to the server while they are processed, even though VEIL does not store them.
            </li>
            <li>
              <strong>A malicious update.</strong> You trust the code your browser loads. Verify builds where possible.
            </li>
          </ul>
        </section>
      </div>
    </div>
  );
}
