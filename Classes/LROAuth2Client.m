//
//  LROAuth2Client.m
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import "LROAuth2Client.h"
#import "ASIHTTPRequest.h"
#import "NSURL+QueryInspector.h"
#import "LROAuth2AccessToken.h"
#import "NSDictionary+QueryString.h"

#pragma mark -

@implementation LROAuth2Client

@synthesize clientID;
@synthesize clientSecret;
@synthesize redirectURL;
@synthesize cancelURL;
@synthesize userURL;
@synthesize tokenURL;
@synthesize delegate;
@synthesize accessToken;
@synthesize debug;

- (id)initWithClientID:(NSString *)_clientID 
                secret:(NSString *)_secret 
           redirectURL:(NSURL *)url;
{
  if (self = [super init]) {
    clientID = [_clientID copy];
    clientSecret = [_secret copy];
    redirectURL = [url copy];
    requests = [[NSMutableArray alloc] init];
    debug = YES;
  }
  return self;
}

- (void)dealloc;
{
  for (ASIHTTPRequest *request in requests) {
    [request setDelegate:nil];
    [request cancel];
  }
  [requests release];
  [accessToken release];
  [clientID release];
  [clientSecret release];
  [userURL release];
  [tokenURL release];
  [redirectURL release];
  [cancelURL release];
  [super dealloc];
}

#pragma mark -
#pragma mark Authorization

- (NSURLRequest *)userAuthorizationRequestWithParameters:(NSDictionary *)additionalParameters;
{
  NSDictionary *params = [NSMutableDictionary dictionary];
  [params setValue:@"web_server" forKey:@"type"];
  [params setValue:clientID forKey:@"client_id"];
  [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
  
  if (additionalParameters) {
    for (NSString *key in additionalParameters) {
      [params setValue:[additionalParameters valueForKey:key] forKey:key];
    }
  }  
  NSURL *fullURL = [NSURL URLWithString:[[self.userURL absoluteString] stringByAppendingFormat:@"?%@", [params stringWithFormEncodedComponents]]];
  NSMutableURLRequest *authRequest = [NSMutableURLRequest requestWithURL:fullURL];
  [authRequest setHTTPMethod:@"GET"];
  
  if(self.debug) {
    NSLog(@"URL: %@", fullURL);
  }

  return [[authRequest copy] autorelease];
}

- (void)verifyAuthorizationWithAccessCode:(NSString *)accessCode;
{
  @synchronized(self) {
    if (isVerifying) return; // don't allow more than one auth request
    
    isVerifying = YES;
      
    NSDictionary *params = [NSMutableDictionary dictionary];
    [params setValue:@"web_server" forKey:@"type"];
    //[params setValue:clientID forKey:@"client_id"];
    [params setValue:@"authorization_code" forKey:@"grant_type"];
    [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
    //[params setValue:clientSecret forKey:@"client_secret"];
    [params setValue:accessCode forKey:@"code"];
      
    ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:self.tokenURL];
    [request setRequestMethod:@"POST"];
    [request addRequestHeader:@"Content-Type" value:@"application/x-www-form-urlencoded"];
    [request appendPostData:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];
    [request setDelegate:self];
    [requests addObject:request];
    [request setUsername:clientID];
    [request setPassword:clientSecret];
    [request startAsynchronous];
    
    if(self.debug) {
      NSLog(@"Request: POST %@\n%@\n\n%@", self.tokenURL, [request requestHeaders], [params stringWithFormEncodedComponents]);
    }
  }
}

- (void)refreshAccessToken:(LROAuth2AccessToken *)_accessToken;
{
  self.accessToken = [_accessToken retain];
  
  NSDictionary *params = [NSMutableDictionary dictionary];
  [params setValue:@"refresh" forKey:@"type"];
  //[params setValue:clientID forKey:@"client_id"];
  [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
  //[params setValue:clientSecret forKey:@"client_secret"];
  [params setValue:_accessToken.refreshToken forKey:@"refresh_token"];
  
  ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:self.tokenURL];
  [request setRequestMethod:@"POST"];
  [request addRequestHeader:@"Content-Type" value:@"application/x-www-form-urlencoded"];
  [request appendPostData:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];
  [request setDelegate:self];
  [requests addObject:request];
  [request setUsername:clientID];
  [request setPassword:clientSecret];
  [request startAsynchronous];
}

#pragma mark -
#pragma mark ASIHTTPRequestDelegate methods

- (void)requestStarted:(ASIHTTPRequest *)request
{
  if (self.debug) {
    NSLog(@"[oauth] starting verification request");
  }
}

- (void)requestFinished:(ASIHTTPRequest *)request
{
  if (self.debug) {
    NSLog(@"[oauth] finished verification request, %@ (%d)", [request responseString], [request responseStatusCode]);
  }
  
  NSError *parseError = nil;
  NSDictionary *authorizationData = [[request responseString] JSONValue];
    
  if(self.debug) {
      NSLog(@"AuthorizationData: %@", authorizationData);
  }
    
  if (parseError) {
    // try and decode the response body as a query string instead
    NSString *responseString = [[NSString alloc] initWithData:[request responseData] encoding:NSUTF8StringEncoding];
    authorizationData = [NSDictionary dictionaryWithFormEncodedString:responseString];
    if ([authorizationData valueForKey:@"access_token"] == nil) { 
      // TODO handle complete parsing failure
      NSAssert(NO, @"Unhandled parsing failure");
    }
  }  
  if (accessToken == nil) {
    self.accessToken = [[LROAuth2AccessToken alloc] initWithAuthorizationResponse:authorizationData];
    if ([self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessToken:)]) {
      [self.delegate oauthClientDidReceiveAccessToken:self];
    } 
  } else {
    [accessToken refreshFromAuthorizationResponse:authorizationData];
    if ([self.delegate respondsToSelector:@selector(oauthClientDidRefreshAccessToken:)]) {
      [self.delegate oauthClientDidRefreshAccessToken:self];
    }
  }  
    
  isVerifying = NO;
  
  [requests removeObject:request];
}

- (void)requestFailed:(ASIHTTPRequest *)request
{
  if (self.debug) {
    NSLog(@"[oauth] request failed with code %d, %@", [request responseStatusCode], [request responseString]);
  }
}

@end

@implementation LROAuth2Client (UIWebViewIntegration)

- (void)authorizeUsingWebView:(UIWebView *)webView;
{
  [self authorizeUsingWebView:webView additionalParameters:nil];
}

- (void)authorizeUsingWebView:(UIWebView *)webView additionalParameters:(NSDictionary *)additionalParameters;
{
  [webView setDelegate:self];
  [webView loadRequest:[self userAuthorizationRequestWithParameters:additionalParameters]];
}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType;
{  
  if ([[request.URL absoluteString] hasPrefix:[self.redirectURL absoluteString]]) {
    [self extractAccessCodeFromCallbackURL:request.URL];

    return NO;
  } else if (self.cancelURL && [[request.URL absoluteString] hasPrefix:[self.cancelURL absoluteString]]) {
    if ([self.delegate respondsToSelector:@selector(oauthClientDidCancel:)]) {
      [self.delegate oauthClientDidCancel:self];
    }
    
    return NO;
  }
  return YES;
}

- (void)setAccessToken:(LROAuth2AccessToken *)token {
    [accessToken autorelease];
    accessToken = [token retain];
    
    // Send notification that the token has changed
    [[NSNotificationCenter defaultCenter] postNotificationName:OAuthAccessTokenChangedNotification object:accessToken];
}

/**
 * custom URL schemes will typically cause a failure so we should handle those here
 */
- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
  NSString *failingURLString = [error.userInfo objectForKey:NSErrorFailingURLStringKey];
  
  if ([failingURLString hasPrefix:[self.redirectURL absoluteString]]) {
    [webView stopLoading];
    if(self.debug) {
      NSLog(@"Webview Failed");
    }
    [self extractAccessCodeFromCallbackURL:[NSURL URLWithString:failingURLString]];
  } else if (self.cancelURL && [failingURLString hasPrefix:[self.cancelURL absoluteString]]) {
    [webView stopLoading];
    if ([self.delegate respondsToSelector:@selector(oauthClientDidCancel:)]) {
      [self.delegate oauthClientDidCancel:self];
    }
  }
}

- (void)extractAccessCodeFromCallbackURL:(NSURL *)callbackURL;
{
  NSString *accessCode = [[callbackURL queryDictionary] valueForKey:@"code"];
  if(self.debug) {
    NSLog(@"Query: %@", callbackURL);
    NSLog(@"Access-code: %@", accessCode);
  }
    
  if ([self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessCode:)]) {
    [self.delegate oauthClientDidReceiveAccessCode:self];
  }
  [self verifyAuthorizationWithAccessCode:accessCode];
}

@end
