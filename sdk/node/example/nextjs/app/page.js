export default function Home() {
  return (
    <main>
      <h1>Sentinel AI SDK — Next.js example</h1>
      <p>
        Every request passes through the Sentinel guard in <code>middleware.js</code>.
        <br />
        <code>/blocked</code> is blocked by an ACL rule; every other path passes.
      </p>
    </main>
  );
}
