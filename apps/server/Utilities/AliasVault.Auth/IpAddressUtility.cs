//-----------------------------------------------------------------------
// <copyright file="IpAddressUtility.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Auth;

using Microsoft.AspNetCore.Http;

/// <summary>
/// Ip address utility class to extract IP address from HttpContext.
/// </summary>
public static class IpAddressUtility
{
    /// <summary>
    /// Extract IP address from HttpContext.
    /// </summary>
    /// <param name="httpContext">HttpContext to extract the IP address from.</param>
    /// <returns>Ip address.</returns>
    public static string GetIpFromContext(HttpContext? httpContext)
    {
        string ipAddress = string.Empty;

        if (httpContext == null)
        {
            return ipAddress;
        }

        // Use RemoteIpAddress which is populated by ForwardedHeadersMiddleware if behind a proxy.
        // We do not manually parse X-Forwarded-For anymore to prevent IP spoofing, as the middleware handles trust.
        ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "0.0.0.0";

        // Anonymize the last octet of the IP address.
        if (ipAddress.Contains('.'))
        {
            try
            {
                ipAddress = ipAddress.Split('.')[0] + "." + ipAddress.Split('.')[1] + "." + ipAddress.Split('.')[2] + ".xxx";
            }
            catch
            {
                // If an exception occurs, continue execution with original IP address.
            }
        }

        return ipAddress;
    }
}
