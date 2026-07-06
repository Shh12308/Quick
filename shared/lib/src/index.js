// shared/lib/src/index.js

// HTTP Client for service-to-service calls
export class ServiceClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
  }

  async get(path, options = {}) {
    return this.request('GET', path, options);
  }

  async post(path, body, options = {}) {
    return this.request('POST', path, { ...options, body });
  }

  async patch(path, body, options = {}) {
    return this.request('PATCH', path, { ...options, body });
  }

  async request(method, path, options = {}) {
    const url = `${this.baseUrl}${path}`;
    const response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    
    if (!response.ok) {
      throw new Error(`Service error: ${response.status} ${response.statusText}`);
    }
    
    return response.json();
  }
}

// Pre-configured clients
export const authClient = new ServiceClient(process.env.AUTH_SERVICE_URL || 'http://auth-service:3001');
export const userClient = new ServiceClient(process.env.USER_SERVICE_URL || 'http://user-service:3002');
export const streamClient = new ServiceClient(process.env.STREAM_SERVICE_URL || 'http://stream-service:3003');
export const paymentClient = new ServiceClient(process.env.PAYMENT_SERVICE_URL || 'http://payment-service:3004');
export const storageClient = new ServiceClient(process.env.STORAGE_SERVICE_URL || 'http://storage-service:3005');
export const chatClient = new ServiceClient(process.env.CHAT_SERVICE_URL || 'http://chat-service:3006');
export const notificationClient = new ServiceClient(process.env.NOTIFICATION_SERVICE_URL || 'http://notification-service:3007');
export const callClient = new ServiceClient(process.env.CALL_SERVICE_URL || 'http://call-service:3008');
export const aiClient = new ServiceClient(process.env.AI_SERVICE_URL || 'http://ai-service:3009');

// Auth middleware for Express
export function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  return authClient.get('/api/auth/verify', {
    headers: { Authorization: `Bearer ${token}` }
  })
    .then(({ valid, user }) => {
      if (!valid) return res.status(401).json({ error: 'Invalid token' });
      req.user = user;
      next();
    })
    .catch(() => res.status(401).json({ error: 'Auth failed' }));
}

// Message Queue publisher
export class MessageQueue {
  constructor(channel) {
    this.channel = channel;
  }
  
  async publish(queue, message) {
    await this.channel.assertQueue(queue, { durable: true });
    this.channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)));
  }
}

// Logger
export const logger = {
  info: (message, meta = {}) => console.log(JSON.stringify({ level: 'info', message, ...meta, timestamp: new Date().toISOString() })),
  error: (message, meta = {}) => console.error(JSON.stringify({ level: 'error', message, ...meta, timestamp: new Date().toISOString() })),
  warn: (message, meta = {}) => console.warn(JSON.stringify({ level: 'warn', message, ...meta, timestamp: new Date().toISOString() }))
};

// Circuit Breaker
export class CircuitBreaker {
  constructor(fn, options = {}) {
    this.fn = fn;
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 30000;
    this.failures = 0;
    this.state = 'CLOSED';
    this.lastFailure = null;
  }

  async execute(...args) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailure > this.resetTimeout) {
        this.state = 'HALF_OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await this.fn(...args);
      this.failures = 0;
      this.state = 'CLOSED';
      return result;
    } catch (err) {
      this.failures++;
      this.lastFailure = Date.now();
      
      if (this.failures >= this.failureThreshold) {
        this.state = 'OPEN';
      }
      
      throw err;
    }
  }
}
