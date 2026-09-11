import appleLogo from "@/assets/idp/apple.svg";
import bitbucketLogo from "@/assets/idp/bitbucket.svg";
import facebookLogo from "@/assets/idp/facebook.svg";
import githubLogo from "@/assets/idp/github.svg";
import gitlabLogo from "@/assets/idp/gitlab.svg";
import googleLogo from "@/assets/idp/google.svg";
import instagramLogo from "@/assets/idp/instagram.svg";
import linkedinLogo from "@/assets/idp/linkedin.svg";
import microsoftLogo from "@/assets/idp/microsoft.svg";
import oktaLogo from "@/assets/idp/okta.svg";
import paypalLogo from "@/assets/idp/paypal.svg";
import stackoverflowLogo from "@/assets/idp/stackoverflow.svg";
import xLogo from "@/assets/idp/x.svg";
import { emptyOidcDraft, type OidcDraft } from "./forms";

export type ProviderAvailability = "ready" | "manual" | "backend";

export interface ProviderPreset {
  id: string;
  name: string;
  logo?: string;
  glyph?: "preview" | "server";
  protocol: string;
  availability: ProviderAvailability;
  draft?: Partial<OidcDraft>;
}

export const PROVIDER_CATALOG: ProviderPreset[] = [
  {
    id: "google",
    name: "Google",
    logo: googleLogo,
    protocol: "OpenID Connect",
    availability: "ready",
    draft: {
      issuer: "https://accounts.google.com",
      authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
      scope: "openid email profile",
      algorithms: "RS256",
    },
  },
  {
    id: "microsoft",
    name: "Microsoft",
    logo: microsoftLogo,
    protocol: "OpenID Connect",
    availability: "manual",
    draft: { scope: "openid email profile", algorithms: "RS256" },
  },
  { id: "github", name: "GitHub", logo: githubLogo, protocol: "OAuth 2.0", availability: "backend" },
  {
    id: "gitlab",
    name: "GitLab",
    logo: gitlabLogo,
    protocol: "OpenID Connect",
    availability: "ready",
    draft: {
      issuer: "https://gitlab.com",
      authorizationEndpoint: "https://gitlab.com/oauth/authorize",
      tokenEndpoint: "https://gitlab.com/oauth/token",
      jwksUri: "https://gitlab.com/oauth/discovery/keys",
      scope: "openid email profile",
      algorithms: "RS256",
    },
  },
  { id: "bitbucket", name: "Bitbucket", logo: bitbucketLogo, protocol: "OAuth 2.0", availability: "backend" },
  {
    id: "okta",
    name: "Okta",
    logo: oktaLogo,
    protocol: "OpenID Connect",
    availability: "manual",
    draft: { scope: "openid email profile", algorithms: "RS256" },
  },
  {
    id: "facebook",
    name: "Facebook",
    logo: facebookLogo,
    protocol: "OpenID Connect",
    availability: "ready",
    draft: {
      issuer: "https://www.facebook.com",
      authorizationEndpoint: "https://www.facebook.com/v18.0/dialog/oauth",
      tokenEndpoint: "https://graph.facebook.com/v18.0/oauth/access_token",
      jwksUri: "https://www.facebook.com/.well-known/oauth/openid/jwks/",
      scope: "openid email",
      algorithms: "RS256",
    },
  },
  { id: "twitter", name: "Twitter / X", logo: xLogo, protocol: "OAuth 2.0", availability: "backend" },
  { id: "instagram", name: "Instagram", logo: instagramLogo, protocol: "OAuth 2.0", availability: "backend" },
  { id: "linkedin", name: "LinkedIn", logo: linkedinLogo, protocol: "OpenID Connect", availability: "backend" },
  {
    id: "apple",
    name: "Apple",
    logo: appleLogo,
    protocol: "OpenID Connect",
    availability: "manual",
    draft: {
      issuer: "https://appleid.apple.com",
      authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
      tokenEndpoint: "https://appleid.apple.com/auth/token",
      jwksUri: "https://appleid.apple.com/auth/keys",
      scope: "openid email",
      algorithms: "RS256",
    },
  },
  { id: "stackoverflow", name: "Stack Overflow", logo: stackoverflowLogo, protocol: "OAuth 2.0", availability: "backend" },
  { id: "paypal", name: "PayPal", logo: paypalLogo, protocol: "OpenID Connect", availability: "backend" },
  {
    id: "oidc",
    name: "Generic OIDC",
    glyph: "preview",
    protocol: "Discovery or endpoints",
    availability: "manual",
    draft: { scope: "openid email profile", algorithms: "RS256 ES256" },
  },
  { id: "saml", name: "SAML 2.0", glyph: "server", protocol: "Metadata XML", availability: "backend" },
];

export function presetDraft(preset?: ProviderPreset): OidcDraft {
  const empty = emptyOidcDraft();
  if (!preset) return empty;
  return {
    ...empty,
    alias: preset.id,
    displayName: preset.name,
    ...preset.draft,
  };
}
