# Pesapal setup

Use Pesapal API 3.0 sandbox credentials in `.env`. Register the public `https://your-domain/api/billing/pesapal/ipn` endpoint with Pesapal and set the returned GUID as `PESAPAL_IPN_ID`. Set `APP_BASE_URL` to the same HTTPS origin.

The checkout creates a monthly subscription order. Pesapal presents available checkout methods and customers must accept recurring card enrollment on the Pesapal page. The callback and IPN endpoints always obtain the transaction status from Pesapal before activating access.
