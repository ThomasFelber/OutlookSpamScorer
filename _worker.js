const PROTECTED_PREFIXES = ['/Samples', '/Delivery-Reports'];
const VALID_PASSWORD = 'StellenAusschreibung31';
const REALM = 'Outlook Spam-Bewerter';

function isProtected(pathname) {
  return PROTECTED_PREFIXES.some(
    (p) => pathname === p || pathname.startsWith(p + '/')
  );
}

function checkAuth(request) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Basic ')) return false;
  const decoded = atob(auth.slice(6));
  const colon = decoded.indexOf(':');
  if (colon === -1) return false;
  return decoded.slice(colon + 1) === VALID_PASSWORD;
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (isProtected(pathname) && !checkAuth(request)) {
      return new Response('Unauthorized', {
        status: 401,
        headers: {
          'WWW-Authenticate': `Basic realm="${REALM}"`,
          'Content-Type': 'text/plain; charset=utf-8',
        },
      });
    }

    return env.ASSETS.fetch(request);
  },
};
