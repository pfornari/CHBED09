async function addToCart(cartId, productId) {
    try {
        // Agrega el producto al carrito utilizando el cartId
        const addToCartResponse = await fetch(`/api/carts/${cartId}/products/${productId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ productId }),
        });

        const data = await addToCartResponse.json();
        console.log('Product added to the cart:', data);
    } catch (error) {
        console.error('Error adding product to cart:', error);
    }
}



document.addEventListener("DOMContentLoaded", function() {
    const addButtons = document.querySelectorAll(".addProductToCart");

    addButtons.forEach(button => {
        button.addEventListener("click", async function() {
            try {
                // Realiza una solicitud para obtener los carritos existentes
                const existingCartResponse = await fetch(`/api/carts`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                });

                const existingCartsData = await existingCartResponse.json();

                // Verifica si hay carritos existentes
                let cartId;
                const cartIds = existingCartsData.cartIds;

                if (cartIds.length > 0) {
                    // Utiliza el primer ID de la lista de carritos existentes
                    cartId = cartIds[0];
                } else {
                    // Si no hay carritos existentes, crea uno nuevo
                    const newCartResponse = await fetch(`/api/carts`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                    });

                    const { newCartId } = await newCartResponse.json();

                    // Asigna el ID del nuevo carrito
                    cartId = newCartId;
                }

                const productId = button.getAttribute("data-pid");
                console.log(cartId, productId);
                addToCart(cartId, productId);
            } catch (error) {
                console.error('Error obtaining or creating cart:', error);
            }
        });
    });
});

async function logout(buttonId) {
    try {
      // Puedes hacer algo con el ID del botón si es necesario
      console.log(`Cerrando sesión desde el botón con ID: ${buttonId}`);
  
      const response = await fetch('/api/sessions/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });
  
      if (response.ok) {
        console.log('Usuario desconectado exitosamente');
        window.location.href = '/api/users/login';
      } else {
        console.error('Error al cerrar sesión:', response.statusText);
      }
    } catch (error) {
      console.error('Error al cerrar sesión:', error);
    }
  }
  
  document.addEventListener("DOMContentLoaded", function () {
    const logoutButton = document.getElementById('logoutButton');
    if (logoutButton) {
      logoutButton.addEventListener('click', function () {
        logout('logoutButton'); // Pasar el ID del botón a la función logout
      });
    }
  });
  