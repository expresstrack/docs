---
title: Sandbox Testing
post_excerpt: Test ExpressTrack's API with our free sandbox environment. No credit card required.
meta_description: Learn how to use ExpressTrack's sandbox environment for testing package tracking API calls, webhooks, and integrations without any charges.
menu_order: 2
---

# Sandbox Testing

ExpressTrack's sandbox environment is built for developers. Use specific tracking numbers to trigger sandbox behavior and test your integrations at any stage of development - from initial setup to ongoing maintenance and new feature development. Sandbox testing is unlimited and free for any amount of usage.

## Getting Started

Sandbox behavior is automatically triggered when you use specific tracking numbers. No separate API keys or endpoints are needed - just use your regular API key with these test tracking numbers.

## Testing Package Tracking

### Sample Tracking Numbers

Use these tracking numbers to test different scenarios:

```bash
# UPS - Delivered package
1Z999AA1234567890
# Demonstrates: Successful delivery flow with complete event history
# Helps you: Test end-to-end delivery scenarios and verify your UI displays final states correctly

# FedEx - In transit
794698123456
# Demonstrates: Active shipment with ongoing updates
# Helps you: Test real-time tracking displays and ensure your application handles mid-journey status changes

# USPS - Out for delivery
9400100000000000000000
# Demonstrates: Final delivery stage with imminent completion
# Helps you: Test notification systems for delivery day and prepare for completion workflows

# DHL - Exception (delivery failed)
1234567890
# Demonstrates: Error handling and exception scenarios
# Helps you: Build robust error handling and user communication for failed deliveries

# Invalid tracking number (for error testing)
INVALID123
# Demonstrates: API error responses and validation
# Helps you: Test your application's error handling and user feedback mechanisms
```

### Suggest More Scenarios

Didn't find the scenario you're looking for? We're always looking to add more test scenarios that help developers. If you have specific tracking scenarios you'd like to test, [let us know](https://github.com/expresstrack/public/discussions) and we'll consider adding them to the sandbox.

### Example API Call

```bash
# Create a tracking in sandbox (using test tracking number)
curl -X POST "https://api.expresstrack.net/v1/trackings" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tracking_number": "1Z999AA1234567890",
    "carrier_code": "ups",
    "metadata": {
      "order_id": "TEST_ORDER_123"
    }
  }'
```ß

### Response Format

Sandbox responses match production format exactly:

```json
{
  "id": "track_test_123abc",
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
    },
    {
      "timestamp": "2024-03-15T08:15:00Z",
      "status": "OutForDelivery",
      "location": "San Francisco, CA",
      "message": "Package out for delivery"
    }
  ],
  "metadata": {
    "order_id": "TEST_ORDER_123"
  }
}
```

## Testing Webhooks

### Setting Up Webhook Testing

1. **Use a webhook testing service:**
   - [webhook.site](https://webhook.site) - Get a unique URL instantly
   - [ngrok](https://ngrok.com) - Expose your local server
   - [RequestBin](https://requestbin.com) - Temporary webhook endpoints

2. **Define webhook addresses in your account dashboard** - [See webhook setup guide](/docs/webhooks) for detailed instructions

### Webhook Behavior

**Automatic Triggers:**
- Creating a tracking with test numbers
- Status changes during automatic simulation
- Manual status updates

tbd*tb*Timing:**
- **Automatic simulation**: Complete delivery flow over ~3 minutes
- **Manual updates**: Immediate webhook delivery
- **Retry logic**: 3 attempts with exponential backoff

**Webhook payload example:**
```json
{
  "event": "tracking_update",
  "tracking": {
    "id": "track_test_123abc",
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
  },
  "timestamp": "2024-03-15T14:30:00Z"
}
```

### Manual Status Updates

You can manually trigger status changes using the API. Available statuses:

- `Pending` - Just created, not yet tracked
- `InfoReceived` - Carrier has shipping info  
- `InTransit` - Package is moving
- `OutForDelivery` - Will be delivered today
- `Delivered` - Successfully delivered
- `FailedAttempt` - Delivery was attempted but failed
- `Exception` - Problem occurred (delay, damage, etc.)
- `AvailableForPickup` - Ready for pickup at location
- `Expired` - No updates for 30+ days

**Example:**
```bash
curl -X PATCH "https://api.expresstrack.net/v1/trackings/track_test_123abc" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status": "Delivered"}'
```

## Behaviors and Limitations

### Features Available
- All API endpoints work identically to production
- Webhook notifications function normally with test numbers
- Error responses match production format
- Authentication and rate limiting apply

### Rate Limits
- Test tracking numbers use the same rate limits as your production plan
- Test tracking numbers do not count toward your monthly quota

### Data Persistence
- Test tracking data is reset weekly
- Tracking events are simulated, not real
- No actual carrier API calls are made for test numbers
- Webhook delivery attempts follow the same rules as production - [see delivery details](/docs/webhooks#delivery-attempts)

### Features Not Available
- Real carrier tracking data (only for test numbers)
- Production webhook delivery (only for test numbers)
- Analytics and reporting data for test numbers
- Custom branding features for test numbers

## Testing Scenarios

### Success Cases
- **Test tracking numbers return realistic delivery data** - Demonstrates normal API operation and response format
- **Webhooks fire for status changes** - Shows real-time notification flow
- **API responses match production format** - Confirms your code will work identically in production

### Error Cases
- **Invalid tracking numbers return appropriate errors** - Tests your error handling logic
- **Rate limit exceeded returns 429 status** - Demonstrates rate limiting behavior
- **Invalid API key returns 401 status** - Tests authentication error handling
- **Malformed requests return 400 status** - Shows validation error responses

### Edge Cases
- **Test webhook delivery failures** - Simulates network issues and webhook endpoint downtime
- **Verify retry mechanisms** - Demonstrates how the API handles temporary failures
- **Check error handling in your application** - Validates your application's robustness

## Moving to Production

When you're ready to go live:

1. **Use real tracking numbers** from your carriers instead of test numbers
2. **Test with actual shipments** to verify real-world behavior
3. **Monitor webhook delivery** in production
4. **Review rate limits** and upgrade if needed

## Support

- **Sandbox issues:** Check our [GitHub discussions](https://github.com/expresstrack/public/discussions)
- **API questions:** Email support@expresstrack.net
- **Documentation:** Browse our [API reference](/docs/api-reference)

## Next Steps

- [Quick Start Guide](/docs/quickstart) - Learn the basics
- [API Reference](/docs/api-reference) - Complete endpoint documentation
- [SDKs](/docs/sdks) - Use our official libraries
- [Webhooks](/docs/webhooks) - Set up real-time notifications 