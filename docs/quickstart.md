---
title: Getting Started with ExpressTrack
post_excerpt: Learn how to integrate ExpressTrack's multi-carrier package tracking API into your application in minutes.
meta_description: Quick start guide for ExpressTrack API - track shipments across multiple carriers with a single integration. Learn authentication, basic endpoints, and webhook setup.
menu_order: 1
---

# Getting Started with ExpressTrack

Welcome to ExpressTrack! This guide will help you start tracking packages across multiple carriers with our unified API. You'll learn how to authenticate, create trackings, and receive real-time updates.

## Prerequisites

- An ExpressTrack account (sign up at [expresstrack.net](https://expresstrack.net))
- Your API key (find it in your dashboard)
- Basic knowledge of REST APIs

## Quick Start Example

Here's a complete example of tracking a package using our API:

```bash
# Replace YOUR_API_KEY with your actual API key
curl -X POST "https://api.expresstrack.net/trackings" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tracking_number": "1Z999AA1234567890",
    "carrier_code": "ups"
  }'
```

## Authentication

All API requests require an API key. Include it in the Authorization header:

```bash
Authorization: Bearer YOUR_API_KEY
```

## Core Concepts

### Tracking a Package

1. **Create a Tracking**
   ```bash
   POST /trackings
   ```
   ```json
   {
     "tracking_number": "1Z999AA1234567890",
     "carrier_code": "ups",  // Optional - we can auto-detect the carrier
     "metadata": {           // Optional - add your own reference data
       "order_id": "ORD123"
     }
   }
   ```

2. **Check Tracking Status**
   ```bash
   GET /trackings/{tracking_id}
   ```

### Understanding Tracking Statuses

Every tracking will have one of these statuses:

- **Pending** - Just created, not yet tracked
- **InfoReceived** - Carrier has shipping info
- **InTransit** - Package is moving
- **OutForDelivery** - Will be delivered today
- **Delivered** - Successfully delivered
- **FailedAttempt** - Delivery was attempted but failed
- **Exception** - Problem occurred (delay, damage, etc.)
- **AvailableForPickup** - Ready for pickup at location
- **Expired** - No updates for 30+ days

## Real-time Updates

### Setting Up Webhooks

1. Register your webhook endpoint:
   ```bash
   POST /webhooks
   ```
   ```json
   {
     "url": "https://your-domain.com/tracking-updates",
     "secret": "your-webhook-secret"  // Optional but recommended
   }
   ```

2. We'll POST updates to your URL when tracking status changes:
   ```json
   {
     "event": "tracking_update",
     "tracking": {
       "id": "track_123abc",
       "tracking_number": "1Z999AA1234567890",
       "status": "Delivered",
       "events": [
         {
           "timestamp": "2024-03-15T14:30:00Z",
           "status": "Delivered",
           "location": "San Francisco, CA",
           "message": "Package delivered to recipient"
         }
       ]
     }
   }
   ```

## Next Steps

- Explore our [complete API reference](/docs/api-reference)
- Check out our [SDK examples](/docs/sdks)
- View supported [carriers](/docs/carriers)
- Join our [developer community](https://github.com/expresstrack/public/discussions)

## Rate Limits and Quotas

- Free tier: 100 trackings/month
- Pay-as-you-go: Starting at $0.10 per tracking
- Enterprise: Contact us for volume pricing
- API rate limit: 60 requests per minute

## Need Help?

- Developer Support: [GitHub Discussions](https://github.com/expresstrack/public/discussions)
- Email: support@expresstrack.net
- Documentation: [docs.expresstrack.net](https://docs.expresstrack.net)
- Status page: [status.expresstrack.net](https://status.expresstrack.net) 