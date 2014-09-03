from django.conf.urls import patterns, include, url

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^request/', 'function_description_db.views.request_handler'),
    url(r'^submit/', 'function_description_db.views.submit_handler'),
    url(r'^compare/', 'function_description_db.views.compare_handler'),
    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Next line to enables the admin:
    url(r'^admin/', include(admin.site.urls)),
)
