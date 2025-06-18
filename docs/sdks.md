---
title: ExpressTrack SDKs & Examples
post_excerpt: Official ExpressTrack SDKs and code examples for tracking packages across multiple carriers in your preferred programming language.
meta_description: Integrate ExpressTrack's multi-carrier package tracking API using our official SDKs for JavaScript, PHP, Python, and more. Includes ready-to-use code examples.
menu_order: 3
---

# ExpressTrack SDKs & Examples

Choose your preferred programming language to get started with ExpressTrack integration. Each SDK provides a clean, idiomatic way to interact with our API.

## JavaScript/TypeScript SDK

```javascript
import { ExpressTrack } from '@expresstrack/sdk';

const tracker = new ExpressTrack('YOUR_API_KEY');

// Create a tracking
const tracking = await tracker.createTracking({
  trackingNumber: '1Z999AA1234567890',
  carrierCode: 'ups',
  metadata: { orderId: 'ORD123' }
});

// Get tracking status
const status = await tracker.getTracking(tracking.id);
console.log(status);

// Set up webhook
await tracker.createWebhook({
  url: 'https://your-domain.com/webhook',
  secret: 'your-secret'
});
```

[View on npm](https://www.npmjs.com/package/@expresstrack/sdk) | [GitHub Repository](https://github.com/expresstrack/sdk-js)

## PHP SDK

```php
<?php
require_once 'vendor/autoload.php';

use ExpressTrack\Client;

$tracker = new Client('YOUR_API_KEY');

// Create a tracking
$tracking = $tracker->trackings->create([
    'tracking_number' => '1Z999AA1234567890',
    'carrier_code' => 'ups',
    'metadata' => ['order_id' => 'ORD123']
]);

// Get tracking status
$status = $tracker->trackings->get($tracking->id);
print_r($status);

// Set up webhook
$tracker->webhooks->create([
    'url' => 'https://your-domain.com/webhook',
    'secret' => 'your-secret'
]);
```

[View on Packagist](https://packagist.org/packages/expresstrack/sdk) | [GitHub Repository](https://github.com/expresstrack/sdk-php)

## Python SDK

```python
from expresstrack import ExpressTrack

tracker = ExpressTrack('YOUR_API_KEY')

# Create a tracking
tracking = tracker.trackings.create(
    tracking_number='1Z999AA1234567890',
    carrier_code='ups',
    metadata={'order_id': 'ORD123'}
)

# Get tracking status
status = tracker.trackings.get(tracking.id)
print(status)

# Set up webhook
tracker.webhooks.create(
    url='https://your-domain.com/webhook',
    secret='your-secret'
)
```

[View on PyPI](https://pypi.org/project/expresstrack/) | [GitHub Repository](https://github.com/expresstrack/sdk-python)

## cURL Examples

If you prefer to use the API directly or are using a different programming language, here are the equivalent cURL commands:

```bash
# Create a tracking
curl -X POST "https://api.expresstrack.net/trackings" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tracking_number": "1Z999AA1234567890",
    "carrier_code": "ups",
    "metadata": {
      "order_id": "ORD123"
    }
  }'

# Get tracking status
curl -X GET "https://api.expresstrack.net/trackings/TRACKING_ID" \
  -H "Authorization: Bearer YOUR_API_KEY"

# Set up webhook
curl -X POST "https://api.expresstrack.net/webhooks" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-domain.com/webhook",
    "secret": "your-secret"
  }'
```

## Community SDKs

Our community has created additional SDKs for other languages. While not officially supported, they might be helpful:

- [Ruby SDK](https://github.com/community/expresstrack-ruby)
- [Go SDK](https://github.com/community/expresstrack-go)
- [.NET SDK](https://github.com/community/expresstrack-dotnet)

Want to contribute? Check out our [SDK development guidelines](https://github.com/expresstrack/sdk-guide) or join the discussion in our [GitHub community](https://github.com/expresstrack/public/discussions).

## Need Help?

- Browse our [example projects](https://github.com/expresstrack/examples)
- Join our [developer community](https://github.com/expresstrack/public/discussions)
- Check the [API Reference](/docs/api-reference)
- Email us at support@expresstrack.net 