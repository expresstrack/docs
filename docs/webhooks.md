---
title: Webhooks
post_excerpt: Set up real-time notifications for tracking updates using ExpressTrack webhooks.
meta_description: Learn how to configure webhooks for ExpressTrack tracking updates, understand payload formats, and implement secure webhook handling.
menu_order: 4
---

# Webhooks

ExpressTrack webhooks provide real-time notifications when tracking status changes. Configure webhook endpoints to receive automatic updates instead of polling the API.

## Overview

Webhooks send HTTP POST requests to your server when tracking events occur. This enables real-time updates for your application without constant API polling.

## Setting Up Webhooks

### 1. Configure Webhook Endpoints

In your ExpressTrack dashboard:

1. Navigate to **Settings** → **Webhooks**
2. Add your webhook URL (must be HTTPS)
3. Optionally set a webhook secret for security
4. Save your configuration

### 2. Webhook URL Requirements

- **HTTPS required** - Webhooks only work with secure URLs
- **Publicly accessible** - Your endpoint must be reachable from the internet
- **POST method** - ExpressTrack sends POST requests only
- **JSON content** - All webhook payloads are JSON format

### 3. Webhook Secret (Recommended)

Set a webhook secret to verify webhook authenticity:

1. Generate a random secret (32+ characters)
2. Add it to your webhook configuration
3. Verify the signature in your webhook handler

## Webhook Events

### tracking_update

Triggered when a tracking status changes:

```json
{
  "event": "tracking_update",
  "tracking": {
    "id": "track_123abc",
    "tracking_number": "1Z999AA1234567890",
    "carrier_code": "ups",
    "status": "Delivered",
    "created_at": "2024-03-15T10:00:00Z",
    "updated_at": "2024-03-15T14:30:00Z",
    "events": [
      {
        "timestamp": "2024-03-15T14:30:00Z",
        "status": "Delivered",
        "location": "San Francisco, CA",
        "message": "Package delivered to recipient"
      }
    ],
    "metadata": {
      "order_id": "ORD123"
    }
  },
  "timestamp": "2024-03-15T14:30:00Z"
}
```

### tracking_created

Triggered when a new tracking is created:

```json
{
  "event": "tracking_created",
  "tracking": {
    "id": "track_123abc",
    "tracking_number": "1Z999AA1234567890",
    "carrier_code": "ups",
    "status": "Pending",
    "created_at": "2024-03-15T10:00:00Z",
    "updated_at": "2024-03-15T10:00:00Z",
    "events": [],
    "metadata": {
      "order_id": "ORD123"
    }
  },
  "timestamp": "2024-03-15T10:00:00Z"
}
```

## Webhook Security

### Verifying Webhook Signatures

ExpressTrack signs webhook payloads with your webhook secret. Verify signatures to ensure webhooks are authentic:

```javascript
const crypto = require('crypto');

function verifyWebhookSignature(payload, signature, secret) {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// In your webhook handler
app.post('/webhook', (req, res) => {
  const signature = req.headers['x-expresstrack-signature'];
  const payload = JSON.stringify(req.body);
  
  if (!verifyWebhookSignature(payload, signature, process.env.WEBHOOK_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  
  // Process webhook
  res.status(200).send('OK');
});
```

### Security Best Practices

1. **Always verify signatures** - Never trust webhooks without verification
2. **Use HTTPS** - Webhook endpoints must be secure
3. **Validate payloads** - Check that required fields are present
4. **Handle duplicates** - Webhooks may be sent multiple times
5. **Respond quickly** - Return 200 status within 5 seconds

## Webhook Delivery

### Delivery Attempts {#delivery-attempts}

ExpressTrack attempts webhook delivery with these rules:

- **Initial attempt** - Sent immediately when event occurs
- **Retry attempts** - Up to 3 retries with exponential backoff
- **Retry intervals** - 1 minute, 5 minutes, 15 minutes
- **Total timeout** - 30 minutes from initial attempt

### Response Requirements

Your webhook endpoint must:

- **Return 200 status** - Within 5 seconds of receiving the webhook
- **Handle POST requests** - Accept JSON payloads
- **Be idempotent** - Handle duplicate webhooks safely
- **Log webhooks** - For debugging and audit purposes

### Failed Deliveries

Webhooks that fail delivery (non-200 response or timeout):

- Are retried automatically
- Appear in your dashboard under **Webhook History**
- Can be manually retried from the dashboard
- Are marked as failed after 3 attempts

## Implementation Examples

### Node.js/Express

```javascript
const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

app.post('/webhook', (req, res) => {
  // Verify signature
  const signature = req.headers['x-expresstrack-signature'];
  const payload = JSON.stringify(req.body);
  
  if (!verifySignature(payload, signature)) {
    return res.status(401).send('Invalid signature');
  }
  
  // Process webhook
  const { event, tracking } = req.body;
  
  switch (event) {
    case 'tracking_update':
      console.log(`Tracking ${tracking.tracking_number} updated to ${tracking.status}`);
      // Update your database, send notifications, etc.
      break;
    case 'tracking_created':
      console.log(`New tracking created: ${tracking.tracking_number}`);
      break;
  }
  
  res.status(200).send('OK');
});
```

### Python/Flask

```python
from flask import Flask, request, jsonify
import hmac
import hashlib

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    # Verify signature
    signature = request.headers.get('x-expresstrack-signature')
    payload = request.get_data()
    
    if not verify_signature(payload, signature):
        return 'Invalid signature', 401
    
    # Process webhook
    data = request.json
    event = data['event']
    tracking = data['tracking']
    
    if event == 'tracking_update':
        print(f"Tracking {tracking['tracking_number']} updated to {tracking['status']}")
    elif event == 'tracking_created':
        print(f"New tracking created: {tracking['tracking_number']}")
    
    return 'OK', 200

def verify_signature(payload, signature):
    expected = hmac.new(
        b'your-webhook-secret',
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)
```

### PHP

```php
<?php
$payload = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_EXPRESSTRACK_SIGNATURE'] ?? '';

// Verify signature
if (!verify_signature($payload, $signature)) {
    http_response_code(401);
    exit('Invalid signature');
}

// Process webhook
$data = json_decode($payload, true);
$event = $data['event'];
$tracking = $data['tracking'];

switch ($event) {
    case 'tracking_update':
        error_log("Tracking {$tracking['tracking_number']} updated to {$tracking['status']}");
        break;
    case 'tracking_created':
        error_log("New tracking created: {$tracking['tracking_number']}");
        break;
}

http_response_code(200);
echo 'OK';

function verify_signature($payload, $signature) {
    $expected = hash_hmac('sha256', $payload, 'your-webhook-secret');
    return hash_equals($expected, $signature);
}
?>
```

## Testing Webhooks

### Using Test Tracking Numbers

Test webhooks using sandbox tracking numbers:

1. Create a tracking with a test number (e.g., `1Z999AA1234567890`)
2. Watch webhooks arrive at your endpoint
3. Test different scenarios with manual status changes

### Webhook Testing Tools

- **[webhook.site](https://webhook.site)** - Get a unique URL instantly
- **[ngrok](https://ngrok.com)** - Expose your local server
- **[RequestBin](https://requestbin.com)** - Temporary webhook endpoints

### Testing Checklist

- [ ] Webhook endpoint accepts POST requests
- [ ] Returns 200 status within 5 seconds
- [ ] Verifies webhook signatures
- [ ] Handles duplicate webhooks safely
- [ ] Logs webhook events for debugging
- [ ] Processes different event types correctly

## Troubleshooting

### Common Issues

**Webhook not received:**
- Check your endpoint is publicly accessible
- Verify HTTPS is enabled
- Check firewall/security group settings
- Review webhook delivery history in dashboard

**Invalid signature errors:**
- Verify webhook secret matches dashboard
- Check signature verification code
- Ensure payload isn't modified by middleware

**Timeout errors:**
- Optimize webhook handler performance
- Return 200 status quickly
- Move heavy processing to background jobs

**Duplicate webhooks:**
- Implement idempotent webhook handling
- Use tracking ID as unique identifier
- Check for existing processed events

### Webhook History

View webhook delivery status in your dashboard:

1. Navigate to **Settings** → **Webhooks**
2. Click **Webhook History**
3. Review delivery attempts and responses
4. Manually retry failed webhooks if needed

## Rate Limits

Webhook delivery follows these limits:

- **Delivery attempts**: 3 per webhook event
- **Concurrent deliveries**: 10 per webhook endpoint
- **Retry intervals**: Exponential backoff (1, 5, 15 minutes)

## Support

- **Webhook issues:** Check [Webhook History](/dashboard/webhooks) in your dashboard
- **Implementation help:** [GitHub Discussions](https://github.com/expresstrack/public/discussions)
- **API questions:** Email support@expresstrack.net

## Next Steps

- [Quick Start Guide](/docs/quickstart) - Learn the basics
- [Sandbox Testing](/docs/sandbox) - Test webhooks with sandbox data
- [API Reference](/docs/api-reference) - Complete endpoint documentation
