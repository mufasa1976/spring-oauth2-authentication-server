import {Injectable} from '@angular/core';
import {HttpEvent, HttpHandler, HttpInterceptor, HttpRequest} from '@angular/common/http';
import {Observable} from 'rxjs';

const XML_HTTP_REQUEST = 'XMLHttpRequest';

@Injectable({
  providedIn: 'root'
})
export class XRequestedWithInterceptor implements HttpInterceptor {

  constructor() { }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(req.clone({setHeaders: {'X-Requested-With': XML_HTTP_REQUEST}}));
  }
}
