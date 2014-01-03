# Event business rules

- user can either save or submit event form at member.checkout page
- saving event
    - would save all requests for quote in the database
    - would **NOT** trigger action to request quote from vendor
    - when the event is loaded, requests for quote in the form will be loaded from **database** and **cookies** merged together
- submitting event
    - would trigger action to request quote from vendor
    - **user can VIEW the event created but will not be able to make amendments to the information submitted**
    - **changes of information has to go through info@drawingboardevents.com.sg
