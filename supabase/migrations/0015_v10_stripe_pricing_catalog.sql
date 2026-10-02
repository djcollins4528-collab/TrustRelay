-- TrustRelay v1.0 commercial monthly pricing.
-- Generated Stripe product/price identifiers are intentionally not stored in this data migration.
update public.billing_plans
set monthly_price_cents = case code
  when 'starter' then 9900
  when 'growth' then 29900
  else monthly_price_cents
end,
updated_at = to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
where code in ('starter','growth');
