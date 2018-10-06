import {BrowserModule} from '@angular/platform-browser';
import {NgModule, Provider} from '@angular/core';

import {AppRoutingModule} from './app-routing.module';
import {AppComponent} from './app.component';
import {HTTP_INTERCEPTORS, HttpClientModule, HttpClientXsrfModule} from '@angular/common/http';
import {StoreModule} from '@ngrx/store';
import {CustomRouterStateSerializer, metaReducers, reducers} from './store';
import {RouterStateSerializer, StoreRouterConnectingModule} from '@ngrx/router-store';
import {XRequestedWithInterceptor} from './interceptors/x-requested-with-interceptor';
import {StoreDevtoolsModule} from '@ngrx/store-devtools';
import {environment} from '../environments/environment';
import {EffectsModule} from '@ngrx/effects';
import {AuthenticationModule} from './authentication/authentication.module';

const HTTP_INTERCEPTOR_PROVIDERS: Provider[] = [
  {provide: HTTP_INTERCEPTORS, useClass: XRequestedWithInterceptor, multi: true}
];

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    AuthenticationModule,
    AppRoutingModule,

    // @angular
    BrowserModule,
    HttpClientModule,
    HttpClientXsrfModule,

    // @ngrx/store
    StoreModule.forRoot(reducers, {metaReducers}),
    StoreRouterConnectingModule.forRoot({stateKey: 'router'}),
    StoreDevtoolsModule.instrument({
      name: 'spring-oauth2-server Store',
      logOnly: environment.production
    }),
    EffectsModule.forRoot([])
  ],
  providers: [
    HTTP_INTERCEPTOR_PROVIDERS,
    {provide: RouterStateSerializer, useClass: CustomRouterStateSerializer}
  ],
  bootstrap: [AppComponent]
})
export class AppModule {}
