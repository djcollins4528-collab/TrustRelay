-- TrustRelay v1.5 security hardening
-- Prevent monetary policy bypass when a request omits the amount.

create or replace function public.trustrelay_evaluate_authority_v07(
  p_authority jsonb,
  p_action text,
  p_resource text,
  p_amount numeric,
  p_currency text,
  p_evidence jsonb
)
returns jsonb
language plpgsql
immutable
set search_path to 'pg_catalog'
as $function$
declare
  v_allowed jsonb := coalesce(p_authority->'allowed','[]'::jsonb);
  v_prohibited jsonb := coalesce(p_authority->'prohibited','[]'::jsonb);
  v_resources jsonb := coalesce(p_authority->'resources','[]'::jsonb);
  v_rules jsonb := coalesce(p_authority->'rules','{}'::jsonb);
  v_escalation jsonb := coalesce(p_authority->'escalation','{}'::jsonb);
  v_pattern text;
  v_resource_match boolean := false;
  v_key text;
  v_limit numeric;
  v_min text;
  v_principal_level text;
  v_rep_level text;
  v_verified_count integer;
begin
  if v_prohibited ? p_action then
    return jsonb_build_object(
      'decision','DENY','reasonCode','ACTION_PROHIBITED',
      'reasonDetail','The action is explicitly prohibited by the grant.'
    );
  end if;

  if not (v_allowed ? p_action) then
    return jsonb_build_object(
      'decision','DENY','reasonCode','ACTION_NOT_ALLOWED',
      'reasonDetail','The action is outside the grant''s allowed scope.'
    );
  end if;

  for v_pattern in select jsonb_array_elements_text(v_resources) loop
    if v_pattern='*'
       or v_pattern=p_resource
       or (right(v_pattern,1)='*'
           and left(p_resource,length(v_pattern)-1)=left(v_pattern,length(v_pattern)-1)) then
      v_resource_match:=true;
      exit;
    end if;
  end loop;

  if not v_resource_match then
    return jsonb_build_object(
      'decision','DENY','reasonCode','RESOURCE_NOT_ALLOWED',
      'reasonDetail','The resource is outside the grant''s resource scope.'
    );
  end if;

  for v_key in select jsonb_object_keys(v_rules) loop
    if v_key not in ('maxAmount','allowedCurrencies','requireEvidence','minimumAssurance','requireVerifiedEvidence') then
      return jsonb_build_object(
        'decision','ESCALATE','reasonCode','POLICY_REVIEW_REQUIRED',
        'reasonDetail','The grant contains policy rules that require manual review.'
      );
    end if;
  end loop;

  if v_rules ? 'minimumAssurance' then
    v_min:=v_rules->>'minimumAssurance';
    v_principal_level:=p_authority->'currentAssurance'->'principal'->>'assuranceLevel';
    v_rep_level:=p_authority->'currentAssurance'->'representative'->>'assuranceLevel';

    if public.trustrelay_assurance_rank_v08(v_min)<0 then
      return jsonb_build_object(
        'decision','ESCALATE','reasonCode','ASSURANCE_POLICY_INVALID',
        'reasonDetail','The minimum assurance policy requires manual review.'
      );
    end if;

    if public.trustrelay_assurance_rank_v08(coalesce(v_principal_level,'none'))<public.trustrelay_assurance_rank_v08(v_min)
       or public.trustrelay_assurance_rank_v08(coalesce(v_rep_level,'none'))<public.trustrelay_assurance_rank_v08(v_min) then
      return jsonb_build_object(
        'decision','DENY','reasonCode','IDENTITY_ASSURANCE_INSUFFICIENT',
        'reasonDetail','One or more parties do not currently meet the grant''s minimum identity assurance level.'
      );
    end if;
  end if;

  -- Any monetary policy must fail closed when the caller omits the amount.
  if (v_rules ? 'maxAmount' or jsonb_typeof(v_rules->'allowedCurrencies')='array')
     and p_amount is null then
    return jsonb_build_object(
      'decision','DENY','reasonCode','AMOUNT_REQUIRED',
      'reasonDetail','An amount is required when the grant contains monetary policy.'
    );
  end if;

  if jsonb_typeof(v_rules->'allowedCurrencies')='array' then
    if nullif(btrim(coalesce(p_currency,'')),'') is null then
      return jsonb_build_object(
        'decision','DENY','reasonCode','CURRENCY_REQUIRED',
        'reasonDetail','A currency is required for this monetary request.'
      );
    end if;

    if not ((v_rules->'allowedCurrencies') ? upper(p_currency)) then
      return jsonb_build_object(
        'decision','DENY','reasonCode','CURRENCY_NOT_ALLOWED',
        'reasonDetail','The requested currency is not permitted by the grant.'
      );
    end if;
  end if;

  if v_rules ? 'maxAmount' then
    begin
      v_limit := (v_rules->>'maxAmount')::numeric;
    exception when others then
      return jsonb_build_object(
        'decision','ESCALATE','reasonCode','POLICY_REVIEW_REQUIRED',
        'reasonDetail','The amount rule could not be evaluated automatically.'
      );
    end;

    if v_limit < 0 then
      return jsonb_build_object(
        'decision','ESCALATE','reasonCode','POLICY_REVIEW_REQUIRED',
        'reasonDetail','The amount rule could not be evaluated automatically.'
      );
    end if;

    if p_amount<0 then
      return jsonb_build_object(
        'decision','DENY','reasonCode','AMOUNT_INVALID',
        'reasonDetail','The requested amount is invalid.'
      );
    end if;

    if p_amount>v_limit then
      if upper(coalesce(v_escalation->>'aboveLimit',''))='ESCALATE' then
        return jsonb_build_object(
          'decision','ESCALATE','reasonCode','AMOUNT_ABOVE_LIMIT',
          'reasonDetail','The amount exceeds the grant limit and requires escalation.'
        );
      end if;
      return jsonb_build_object(
        'decision','DENY','reasonCode','AMOUNT_ABOVE_LIMIT',
        'reasonDetail','The amount exceeds the grant limit.'
      );
    end if;
  end if;

  begin
    v_verified_count:=coalesce((p_evidence->>'verifiedDocumentCount')::integer,0);
  exception when others then
    v_verified_count:=0;
  end;

  if coalesce((v_rules->>'requireVerifiedEvidence')::boolean,false) and v_verified_count<1 then
    return jsonb_build_object(
      'decision','ESCALATE','reasonCode','VERIFIED_EVIDENCE_REQUIRED',
      'reasonDetail','Approved TrustRelay evidence linked to this grant is required.'
    );
  end if;

  if coalesce((v_rules->>'requireEvidence')::boolean,false)
     and (p_evidence is null or p_evidence='{}'::jsonb) then
    return jsonb_build_object(
      'decision','ESCALATE','reasonCode','EVIDENCE_REQUIRED',
      'reasonDetail','Supporting evidence is required before this request can proceed.'
    );
  end if;

  if coalesce((v_escalation->>'always')::boolean,false) then
    return jsonb_build_object(
      'decision','ESCALATE','reasonCode','MANUAL_REVIEW_REQUIRED',
      'reasonDetail','This grant requires manual review for every request.'
    );
  end if;

  return jsonb_build_object(
    'decision','ALLOW','reasonCode','POLICY_SATISFIED',
    'reasonDetail','The requested action satisfies the active authority grant.'
  );
end;
$function$;
