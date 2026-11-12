export interface IpInfo {
  ip: string; success: boolean;
  country: string | null; region: string | null; city: string | null;
  latitude: number | null; longitude: number | null;
  connection: { asn: number | null; isp: string | null; org: string | null; domain: string | null } | null;
}
